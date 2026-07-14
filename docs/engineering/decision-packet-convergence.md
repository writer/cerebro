# Decision Packet Convergence Contract

This document turns #1726 into an implementation handoff. It defines how the
canonical decision packet extends current Cerebro contracts without creating a
second agent control plane, evidence system, action model, or business ledger.

## Outcome

A caller asks one consequential question and receives one bounded,
tenant-authorized packet that states:

- what Cerebro concluded,
- which resolved evidence supports or contradicts the conclusion,
- which required evidence is missing, stale, failed, unsupported, or
  unconfigured,
- which assets, identities, policies, and controls are affected,
- how decision confidence was derived,
- which action may be proposed next,
- which approval is required,
- and which immutable receipt can be referenced when the decision is later
  accepted, rejected, or deferred.

Building a packet never executes an action and never records an actor's final
decision.

## Current Contract Inventory

| Current owner | Shipped behavior | Keep | Change |
| --- | --- | --- | --- |
| `internal/agentplatform.AgentEvidencePacket` | Builds tenant-forced preflight, capability decisions, verifier results, action stages, connector gates, eval guidance, memory guidance, simulation guidance, and confidence from caller-supplied URNs and coverage context. Exposed through HTTP and A2A; supporting contracts are exposed through MCP. | Policy, capability, connector, verifier, and action-stage logic. Existing HTTP JSON and `agent-evidence-packet` A2A artifact. | Name its confidence as agent readiness. Extract a smaller reusable guardrail projection. Do not present it as a resolved decision. |
| `internal/agentplatform.ClaimVerification` | Maps supporting, counter, missing, freshness, coverage, approval, and requested stage inputs to a verdict and allowed next stage. | Verdict and stage-gate logic. | Feed it server-resolved inputs. The decision builder must not accept a caller-declared verdict. |
| `internal/evidencepackets.Response` | Builds audit/control evidence collections, lineage, review state, questionnaire answers, gaps, and export artifacts. | Audit packet ownership and export behavior. | Reference audit packet IDs or selected evidence records; do not embed the full audit export in every decision. |
| `internal/proactivetriage.Service` | Loads findings and memory, builds an agent evidence packet, asks a recommender, and writes an auto-generated knowledge action with a floating-point confidence. | Finding selection, memory lookup, and bounded action write-back. | Make it the first decision-packet adopter. Stop treating model/recommender confidence as decision confidence. |
| `internal/graphactions` | Defines provider action metadata, dry-run results, reversal metadata, approval requirements, execution status, and reconciliation. The current mutation request accepts caller-supplied `approved=true`; it does not bind execution to a durable approval over an immutable proposal. | Action catalog, eligibility, target resolution, provider adapters, and reconciliation primitives. | Convert eligible metadata into proposal previews only. Packet construction cannot call `Execute`. Complete #1760 before treating an approval or execution as trusted workflow state. |
| `internal/knowledge` and `internal/workflowevents` | Build decisions, actions, and outcomes and emit `workflow.v1.knowledge.*` events before graph projection when an append log is configured. | Durable event shapes and workflow projection. | Complete #1740 so append does not depend on graph availability and a missing append log cannot silently produce a graph-only trusted decision. |
| Finding, evidence, source coverage, control, and graph ports | Read current findings, persisted evidence, source runtime state, control mappings, and bounded graph context. | Existing authoritative/current-state reads. | Compose them behind the decision service; do not expose transport request types to the domain package. |

## Semantic Boundaries

### Agent readiness packet

The existing `AgentEvidencePacket` answers: "May this agent run, and which
guardrails apply?"

It may cite caller-supplied URNs, but it does not prove that those URNs resolve,
that the records are fresh, or that contradictory records do not exist.

### Claim verification

`ClaimVerification` answers: "Given these supporting, counter, missing,
freshness, and coverage inputs, how strongly is this claim supported and which
action stage may follow?"

The decision service supplies those inputs after authorization and evidence
resolution.

### Decision packet

The decision packet answers: "What does the authorized, bounded evidence set
support now?"

It owns resolved references, contradictions, coverage gaps, affected subjects,
control applicability, deterministic decision confidence, and the immutable
receipt digest.

### Audit evidence packet

An audit evidence packet answers: "Which evidence and review artifacts support
this control, framework, or audit period?"

It is a larger collection/export grain. A decision packet may reference it but
does not replace it.

### Decision event

A decision event answers: "What did the authenticated actor do with the packet?"

It records accepted, rejected, or deferred state and references the immutable
packet ID. Packet construction and decision recording are separate operations.

### Action proposal and approval receipt

An action proposal answers: "Which exact mutation, target, parameters, reversal,
evidence snapshot, and verification plan may be reviewed?"

The decision packet may return the inputs for a proposal preview. It does not
own the durable action proposal, approval receipt, execution claim, provider
attempt, or verification result. Those records belong to the graph-action
workflow defined by #1760. A packet receipt digest is not an action-proposal
digest, and accepting a decision packet is not approval to execute an action.

## Ownership Flow

```text
authenticated tenant + actor + bounded request
                    |
                    v
        agentplatform guardrails
        - capability and scope gates
        - connector readiness
        - action-stage ceiling
                    |
                    v
      decisionpacket evidence resolver
      - findings, claims, evidence
      - coverage and freshness
      - controls and audit references
      - bounded graph context
                    |
                    v
       agentplatform claim verification
       - supported / weak / contradicted / unknown
                    |
                    v
         decision state + confidence
         + proposals + receipt digest
                    |
          no write side effect
                    |
                    v
       separate accept / reject / defer
       -> durable knowledge decision event
       -> optional graph projection
                    |
                    | if a mutation is requested
                    v
       separate graph-action workflow (#1760)
       -> immutable action proposal digest
       -> authenticated approval receipt
       -> durable execution claim
       -> provider reconciliation
       -> fresh finding verification
```

## Prerequisite: Durable Business Ledger

Complete #1740 before the first decision packet can be accepted as a completed
business decision.

The required invariant is:

```text
authorized command -> durable append -> optional projection
```

The current graph-first availability check must not remain:

```text
graph available -> maybe append -> graph projection
```

Packet reads may still use bounded Neo4j context. Packet receipts and accepted
decision events must remain durable when Neo4j is unavailable.

## Prerequisite: Durable Action Approval

Complete #1760 before any packet-generated proposal can authorize mutation.
The required invariant is:

```text
packet receipt
  -> immutable action proposal digest
  -> authenticated approval receipt over that digest
  -> durable execution claim
  -> provider submission and reconciliation
  -> fresh evidence verification
  -> finding closeout
```

These shortcuts are explicitly invalid:

- using `approved=true` as approval evidence,
- treating the graph-action write scope as approval of a specific proposal,
- reusing the packet receipt digest as the action proposal digest,
- changing a target, parameter, reason, ticket, reversal, evidence revision, or
  verification plan after approval,
- treating provider success or a reconciled external status as proof that the
  finding is fixed,
- or allowing packet construction or proactive triage to claim an execution.

Proposal and execution state remain available when Neo4j is unavailable. A
projection failure cannot reopen the approval gate or repeat provider dispatch.

## Target Package Contracts

### Reusable agent guardrails

Add a pure projection in `internal/agentplatform`:

```go
type AgentDecisionGuardrails struct {
    Version            string
    Preflight          AgentRunPreflight
    VerifierResults    []AgentVerifierResult
    ActionLadder       []AgentActionStageStatus
    ConnectorToolGates []ConnectorToolGateDecision
    Readiness          AgentReadinessAssessment
    RequiredWriteBack  []string
}

type AgentReadinessAssessment struct {
    State   string
    Reasons []string
}
```

Allowed readiness states are `ready`, `ready_with_warnings`, and `blocked`.
They are not decision confidence levels.

Add `BuildAgentDecisionGuardrails`. Keep `BuildEvidencePacket` as a
compatibility wrapper that calls the new builder and then adds existing agent
profiles, eval checklist, memory plan, and simulation plan. The serialized
legacy response must remain byte-for-byte equivalent after canonical JSON
normalization for fixed input and time.

Do not rename the existing HTTP route or A2A skill in this slice.

### Decision request

The authenticated tenant and actor are forced service arguments, not mutable
request fields:

```go
type Request struct {
    Workflow       string
    Question       string
    ScopeURN       string
    FindingIDs     []string
    ClaimIDs       []string
    EvidenceURNs   []string
    AuditPacketIDs []string
    RequiredSources []string
    RequestedAction string
    Budgets        Budgets
}

func (s Service) Build(
    ctx context.Context,
    tenant AuthorizedTenant,
    actor AuthorizedActor,
    request Request,
) (*Packet, error)
```

The domain request cannot override tenant, actor, approval, execution state, or
claim verdict.

### Decision packet

```go
type Packet struct {
    SchemaVersion  string
    ID             string
    GeneratedAt    time.Time
    Workflow       Workflow
    Scope          Scope
    Guardrails     agentplatform.AgentDecisionGuardrails
    Claim          agentplatform.ClaimVerification
    Decision       Decision
    Confidence     Confidence
    Freshness      Freshness
    Evidence       []EvidenceReference
    Contradictions []Contradiction
    CoverageGaps   []CoverageGap
    Affected       []SubjectReference
    Controls       []ControlReference
    AuditPackets   []AuditPacketReference
    Actions        []ActionProposal
    Provenance     Provenance
    Limits         ResultLimits
}
```

Do not embed raw provider payloads, unrestricted graph rows, model prompts,
model completions, authorization headers, or credentials.

## State Mapping

### Decision states

- `supported`
- `supported_with_gaps`
- `blocked`
- `insufficient_evidence`
- `not_applicable`

### Claim-verdict mapping

| Claim verdict | Initial decision state | Additional rule |
| --- | --- | --- |
| `supported` | `supported` | Any required gap or stale required evidence changes it to `supported_with_gaps`. |
| `weakly_supported` | `supported_with_gaps` | The packet must expose every warning and missing item. |
| `contradicted` | `blocked` | An action proposal may explain remediation but cannot be executable. |
| `unknown` | `insufficient_evidence` | A missing-evidence collection action may be proposed. |

`not_applicable` requires an explicit applicability result from a policy or
control domain resolver. An empty result set is not enough.

### Action proposal states

- `informational`
- `proposal`
- `approval_required`

The packet does not return `approved`, `executing`, `executed`, `verified`, or
`closed`. Those states belong to the durable proposal, approval, execution,
reconciliation, and verification workflow in #1760. A provider-reported
success is not the `verified` state.

## Confidence Contract

Decision confidence uses `high`, `medium`, `low`, and `unknown`.

It is deterministic and rule-derived:

1. No resolved supporting evidence produces `unknown`.
2. Failed, unconfigured, unsupported, or unverified required coverage caps the
   level at `low`.
3. Stale required evidence caps the level at `low`.
4. An unresolved contradiction caps the level at `medium` and sets the
   decision state to `blocked` when it contradicts the primary claim.
5. Partial optional coverage caps the level at `medium` only when the missing
   dimension could change the conclusion.
6. `high` requires fresh supporting evidence, no unresolved contradiction, no
   required gap, and passing tenant/provenance guardrails.

Every cap adds one stable reason code. Human prose may explain the codes but
cannot change the derived level.

Never copy these values from:

- `AgentPacketConfidence`, whose current `blocked` value describes readiness,
- `proactivetriage.Recommendation.Confidence`, which is an uncalibrated float,
- finding risk confidence scores, which describe rule/risk evidence rather than
  the requested decision,
- or an LLM response.

## Evidence Resolution

Use adapters over current ports. The decision package owns orchestration, not
storage implementations.

| Input | Current read boundary | Resolution requirement |
| --- | --- | --- |
| Finding IDs | `ports.FindingStore` | Force tenant, load status/risk/control refs, and retain stable finding/evidence IDs. |
| Finding evidence | `ports.FindingEvidenceStore` | Resolve claim, event, graph-root, run, and observation references. |
| Claims | claim store boundary | Resolve current claim and tenant; do not treat a raw claim ID as proof. |
| Source coverage | source coverage service/read model | Return required, missing, stale, failed, unsupported, unconfigured, and unverified dimensions. |
| Controls and policies | compliance/control registries | Return applicable control IDs and explicit applicability state. |
| Audit packets | evidence packet service/receipt | Return packet ID, scope, period, digest, freshness, and selected evidence refs only. |
| Graph context | `ports.GraphQueryStore` | Use authorized scope roots and the guardrail budget; graph failure becomes an explicit gap unless the workflow requires graph proof. |
| Actions | `graphactions.Registry` and dry-run metadata | Return eligible proposal-preview inputs without calling provider execution. Include the action catalog version and every execution-relevant field needed for #1760 to create its own canonical proposal digest. |

Evidence supplied by a caller is a resolution hint. If an ID is missing,
foreign, deleted, or unauthorized, fail without confirming protected record
existence. If it is authorized but stale or unresolved, represent the gap.

## Initial Budgets

Use explicit defaults and hard maxima:

| Collection | Default | Hard maximum |
| --- | ---: | ---: |
| Supporting evidence references | 50 | 100 |
| Contradictions | 10 | 25 |
| Coverage gaps | 10 | 25 |
| Affected subjects | 50 | 100 |
| Control references | 50 | 100 |
| Audit packet references | 10 | 25 |
| Action proposals | 5 | 10 |
| Graph rows | 25 | 100 |
| Graph depth | 2 | 3 |

Reject negative budgets and values above the hard maximum. The response records
requested limit, applied limit, returned count, total known count when safe, and
`truncated`. Truncation cannot silently produce `supported`; it creates a gap
and caps confidence when omitted records could change the decision.

## Contradiction Detection

Normalize resolvable claims into:

```text
tenant + subject + predicate + value + valid_from + valid_to + source
```

Two records contradict when they refer to the same tenant, subject, and
predicate, assert incompatible normalized values, and have overlapping validity
intervals. Keep both evidence references, source timestamps, and the resolution
state.

Do not infer a contradiction from two different observation times when the
newer record cleanly supersedes the older record. Do not let an LLM decide
whether two records conflict.

## Canonicalization And Receipt

1. Normalize strings, enums, timestamps, URNs, and reason codes.
2. Remove duplicate references by stable type and ID.
3. Sort every repeated field by a documented stable key.
4. Include the injected UTC clock value.
5. Serialize canonical JSON without maps whose key order changes semantics.
6. Hash with SHA-256 and format the ID as `dpr_<first-32-hex>`.
7. Persist the complete bounded/redacted packet plus schema version, evidence
   digest, coverage digest, and expiry.

The same normalized inputs and injected time produce the same ID and JSON. An
updated finding, evidence observation, coverage state, control mapping, or
clock produces a new receipt. Receipts are immutable.

## Packet Receipt Versus Accepted Decision

The receipt proves what Cerebro returned. It does not prove that an actor
accepted it.

Extend the knowledge decision command and event additively with:

- `packet_id`
- `packet_schema_version`
- `packet_digest`
- `decision_disposition`: `accepted`, `rejected`, or `deferred`
- bounded rejection/deferral reason

The authenticated decision event references the packet receipt. A terminal
outcome later references the decision ID. Weekly completed decisions require
both the accepted durable decision and its qualifying outcome; packet-build
counts alone are activity.

## Transport Plan

### New operation

Add one semantic operation through shared service adapters:

```text
BuildDecisionPacket(BuildDecisionPacketRequest)
  returns (BuildDecisionPacketResponse)
```

Expose generated JSON at `POST /platform/decision-packets`. HTTP and Connect
must return the same protobuf-defined packet, error mapping, and limits.

### MCP

Add a task-level read tool only after the HTTP/Connect contract is stable. The
tool calls the same service and returns the same semantic packet. It does not
accept approval or execution fields.

### Legacy compatibility

Keep these unchanged during the first stable schema:

- `POST /api/v1/agent-platform/evidence-packets`
- the A2A `agent-evidence-packet` skill and artifact
- claim-verification HTTP/MCP contracts
- audit evidence packet routes and exports

Document the agent evidence packet as a readiness/guardrail artifact. Do not
alias it to the decision route or silently change its JSON schema.

## Error Contract

| Condition | Domain result | Transport behavior |
| --- | --- | --- |
| Invalid workflow, enum, budget, or malformed URN | validation error | HTTP 400 / Connect invalid argument |
| Missing or unauthorized tenant/scope/reference | authorization or not-found-normalized error | HTTP 403 or tenant-safe 404 according to existing policy; never return a packet |
| Required state store unavailable | dependency unavailable | HTTP 503 / Connect unavailable |
| Optional graph context unavailable | explicit coverage/provenance gap | Return a packet unless the workflow declares graph proof required. |
| Required graph proof unavailable | insufficient evidence | Return a bounded packet with the gap; no action beyond explain/collect evidence. |
| Receipt persistence fails | durability error | Do not return a receipt-bearing success. |
| Action provider unavailable | not applicable during build | Packet construction never contacts the provider executor. |

## First Adopter: Proactive Finding Triage

After the packet read and receipt are stable:

1. Load the finding and memory hints as today.
2. Build a decision packet for `finding_to_verified_fix` with the finding ID and
   primary scope.
3. Generate explanatory prose only from the resolved packet.
4. Permit an action proposal only for `supported` or
   `supported_with_gaps`; copy every gap into the recommendation.
5. For `blocked`, produce an investigation or contradiction-resolution step.
6. For `insufficient_evidence`, produce an evidence-collection step.
7. Replace the uncalibrated recommendation confidence as the authoritative
   value. Persist packet ID, confidence level, confidence reason codes, decision
   state, and trace ID with the auto-generated action.
8. Do not create an approval, claim execution, or call the graph-action
   provider. If an operator chooses the proposal, hand the packet receipt and
   proposal inputs to #1760, which creates a separate immutable proposal.

## Golden Fixtures

Check in deterministic fixtures for:

1. **Supported change decision** — fresh required evidence, complete coverage,
   applicable controls, no contradiction, high confidence.
2. **Partial decision** — one material optional gap, medium confidence, explicit
   proposal limits.
3. **Stale required evidence** — supported claim but low confidence and a
   collection action.
4. **Contradicted finding** — supporting and counterevidence overlap; decision
   blocked and execution unavailable.
5. **No evidence** — insufficient evidence, unknown confidence, no remediation
   proposal.
6. **Unauthorized reference** — transport error with no packet and no protected
   identifier disclosure.
7. **Not applicable control** — explicit applicability result and no false
   missing-evidence failure.
8. **Truncated evidence** — limits recorded, gap present, and confidence capped.

Each fixture asserts canonical JSON, packet ID, decision state, confidence
level and reasons, claim verdict, action ceiling, gaps, and repeated-field
ordering.

## Pull Request Slices

### PR 0: Decision ledger durability

Owner: #1740.

Make knowledge events append-first and independent of Neo4j availability. Do
not start receipt-based decision completion before this gate passes.

### PR 1: Agent guardrail extraction

Files:

- `internal/agentplatform/security_control_plane.go`
- new focused guardrail file and tests
- existing HTTP/A2A/MCP compatibility tests

Deliver `AgentDecisionGuardrails`, `AgentReadinessAssessment`, and the legacy
adapter. No decision package, schema, route, or storage change.

### PR 2: Decision types and deterministic rules

Files:

- `internal/decisionpacket/types.go`
- `normalize.go`
- `confidence.go`
- `contradictions.go`
- golden fixtures and pure tests

No stores, bootstrap imports, transport, graph calls, or persistence.

### PR 3: Evidence-resolving builder

Add narrow adapters over existing finding, evidence, claim, coverage, control,
audit packet, graph query, and action registry boundaries. Add failure injection
for optional and required dependencies. No transport.

### PR 4: Immutable receipt store

Add the ordered migration, Postgres store, tenant-scoped lookup, immutability,
retention, canonical hash verification, and audit tests. Do not project packet
JSON into Neo4j.

### PR 5: HTTP and Connect parity

Add protobuf messages, RPC, generated JSON route, auth policy, OpenAPI, SDK
generation, telemetry labels, shared error mapping, and contract parity tests.

### PR 6: Proactive triage adoption

Replace caller-assembled agent packet reasoning with the resolved decision
packet, persist packet linkage, remove ungrounded recommendation confidence from
decision semantics, and add finding-to-fix fixtures. The adopter may emit a
proposal preview only. It cannot set `approved`, create an approval receipt,
claim an execution, or call a provider.

### PR 7: Task-level MCP read

Add the decision read tool and tool-selection fixtures under #1722. Keep the
legacy agent packet and expert tools during the compatibility window.

## Validation Gates

Every slice runs its focused tests plus:

```bash
make docs-drift-check
make readme-check
git diff --check
```

Transport and persistence slices also run:

```bash
make proto-lint proto-generate-check proto-breaking
make openapi-check
make sdk-test
make check-structural check-structural-test check-arch
make test
make test-race
make docker-smoke
```

## Rollout And Rollback

1. Ship guardrail extraction with no client-visible change.
2. Ship decision types and builder behind no public route.
3. Enable receipt persistence in shadow mode and compare canonical packets
   without returning them to clients.
4. Expose HTTP/Connect to explicit callers.
5. Add proactive triage as the first adopter and compare recommendation state,
   gaps, and packet confidence against the prior path.
6. Add the MCP read tool after contract and selection evals pass.
7. Enable proposal handoff only after #1760 enforces digest-bound approval and
   durable execution claims. Keep all packet surfaces read/proposal-only if that
   dependency is disabled or unhealthy.

Rollback disables new callers and the route. Immutable receipts remain readable
for audit. Legacy agent packet, claim verification, audit packet, and graph
action surfaces remain available throughout. Do not delete compatibility code
until usage telemetry shows no remaining clients and a separate removal PR is
approved.

## Completion Criteria

- One evidence-resolved packet contract is canonical across HTTP, Connect, MCP,
  SDK, proactive triage, and later reports.
- Agent readiness and decision confidence are separate and machine-readable.
- Existing claim-verification and action-stage logic is reused.
- Existing agent and audit packet clients remain compatible.
- Packet receipts are immutable, tenant-scoped, bounded, redacted, and
  independently durable from Neo4j.
- Accepted decisions reference packet receipts through durable events.
- Proactive triage cannot represent an ungrounded model score as decision
  confidence.
- No packet build performs an external action.
- No packet receipt, accepted decision event, agent action stage, or write scope
  can substitute for the action proposal and approval receipt defined by #1760.
- Provider success cannot close a finding without fresh verification evidence.
- Golden fixtures cover supported, partial, stale, contradicted, empty,
  unauthorized, not-applicable, and truncated evidence states.

Refs #1721, #1722, #1726, #1727, #1740, and #1760.
